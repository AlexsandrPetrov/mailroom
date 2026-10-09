// Mailroom — веб-почта. Данные писем выводятся только через textContent / esc().
'use strict';

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));

const state = {
  me: null, csrf: '', folders: [], folder: 'INBOX', page: 1, pages: 1, total: 0, items: [],
  selected: new Set(), current: null, images: false, filters: [], compose: null,
};

// ---------- сеть ----------
async function api(path, options = {}) {
  const opts = {...options, headers: {...(options.headers || {})}};
  if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== 'string') {
    opts.body = JSON.stringify(opts.body);
    opts.headers['Content-Type'] = 'application/json';
  }
  if (opts.method && opts.method !== 'GET') opts.headers['X-CSRF-Token'] = state.csrf;
  let response;
  try { response = await fetch(path, opts); } catch (e) { throw new Error('Нет связи с сервером'); }
  if (response.status === 401) { location.href = '/mail/login'; throw new Error('Сессия завершена'); }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Ошибка ${response.status}`);
  return data;
}
const post = (p, b) => api(p, {method: 'POST', body: b || {}});
const q = (obj) => new URLSearchParams(obj).toString();

function toast(text, error = false) {
  const t = $('#toast');
  t.textContent = text;
  t.className = error ? 'error' : '';
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add('hidden'), error ? 7000 : 3000);
}
const fail = (e) => toast(e.message || String(e), true);

function fmtDate(iso, full = false) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return '';
  const now = new Date();
  if (full) return d.toLocaleString('ru-RU', {dateStyle: 'long', timeStyle: 'short'});
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'});
  if (d.getFullYear() === now.getFullYear()) return d.toLocaleDateString('ru-RU', {day: 'numeric', month: 'short'});
  return d.toLocaleDateString('ru-RU');
}
function fmtSize(b) {
  if (b < 1024) return `${b} Б`;
  if (b < 1048576) return `${(b / 1024).toFixed(0)} КБ`;
  return `${(b / 1048576).toFixed(1)} МБ`;
}
const person = (a) => (a ? (a.name || a.email) : '');
const people = (list) => (list || []).map((a) => (a.name ? `${a.name} <${a.email}>` : a.email)).join(', ');

function setView(view) {
  document.body.classList.remove('view-folders', 'view-list', 'view-reader');
  document.body.classList.add(`view-${view}`);
}
$('#back').addEventListener('click', () => {
  if (document.body.classList.contains('view-reader')) setView('list');
  else setView('folders');
});

// ---------- профиль ----------
async function loadMe() {
  state.me = await api('/api/mail/me');
  state.csrf = state.me.csrf;
  $('#who').textContent = state.me.display_name ? `${state.me.display_name} · ${state.me.address}` : state.me.address;
  const qt = state.me.quota;
  if (qt && qt.limit_kb) {
    const pct = Math.min(100, Math.round(qt.used_kb * 100 / qt.limit_kb));
    $('#quota').innerHTML = `<div class="quota-bar ${pct >= 90 ? 'warn' : ''}"><span></span></div>
      <div>${esc(fmtSize(qt.used_kb * 1024))} из ${esc(fmtSize(qt.limit_kb * 1024))} (${pct}%)</div>
      ${pct >= 90 ? '<div>Ящик почти заполнен: удалите ненужные письма и очистите «Корзину».</div>' : ''}`;
    $('#quota .quota-bar span').style.width = `${pct}%`;
  }
}

// ---------- папки ----------
const icon = (name, cls = '') => `<svg class="i${cls ? ' ' + cls : ''}" aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const ICONS = {INBOX: 'inbox', Drafts: 'draft', Sent: 'send', Junk: 'ban', Trash: 'trash'};
async function loadFolders() {
  state.folders = (await api('/api/mail/folders')).items;
  const list = $('#folder-list');
  list.innerHTML = '';
  for (const f of state.folders) {
    const button = document.createElement('button');
    button.className = `folder${f.name === state.folder ? ' active' : ''}`;
    button.dataset.folder = f.name;
    const depth = f.system ? 0 : f.name.split('/').length - 1;
    button.style.paddingLeft = `${10 + depth * 14}px`;
    button.innerHTML = `${icon(ICONS[f.special] || 'folder')}<span class="name"></span><span class="count"></span>`;
    $('.name', button).textContent = f.title;
    $('.count', button).textContent = f.unseen && f.special !== 'Sent' && f.special !== 'Drafts' ? f.unseen : (f.special === 'Drafts' && f.total ? f.total : '');
    button.title = f.name;
    button.addEventListener('click', () => openFolder(f.name));
    button.addEventListener('dragover', (e) => { e.preventDefault(); button.classList.add('dragover'); });
    button.addEventListener('dragleave', () => button.classList.remove('dragover'));
    button.addEventListener('drop', (e) => { e.preventDefault(); button.classList.remove('dragover'); bulk('move', f.name, JSON.parse(e.dataTransfer.getData('text/plain') || '[]')); });
    list.appendChild(button);
  }
  const move = $('#bulk-move');
  move.innerHTML = '<option value="">Переместить…</option>';
  for (const f of state.folders) {
    const o = document.createElement('option');
    o.value = f.name;
    o.textContent = f.title;
    move.appendChild(o);
  }
  const unread = state.folders.find((f) => f.special === 'INBOX')?.unseen || 0;
  document.title = unread ? `(${unread}) Почта` : 'Почта';
}
const folderInfo = (name = state.folder) => state.folders.find((f) => f.name === name) || {name, title: name, special: null, system: false};

function openFolder(name) {
  state.folder = name;
  state.page = 1;
  state.selected.clear();
  $('#search').value = '';
  $$('.folder').forEach((b) => b.classList.toggle('active', b.dataset.folder === name));
  closeReader();
  setView('list');
  loadList().catch(fail);
}

$('#folder-new').addEventListener('click', async () => {
  const name = prompt('Название новой папки (вложенность — через «/», например «Проекты/2026»):');
  if (!name) return;
  try { await post('/api/mail/folders', {name: name.trim()}); await loadFolders(); toast('Папка создана'); } catch (e) { fail(e); }
});
$('#folder-rename').addEventListener('click', async () => {
  const f = folderInfo();
  const name = prompt('Новое название папки:', f.name);
  if (!name || name === f.name) return;
  try {
    await api('/api/mail/folders', {method: 'PATCH', body: {name: f.name, new_name: name.trim()}});
    state.folder = name.trim();
    await loadFolders();
    await loadList();
  } catch (e) { fail(e); }
});
$('#folder-delete').addEventListener('click', async () => {
  const f = folderInfo();
  if (!confirm(`Удалить папку «${f.title}» вместе с письмами в ней?`)) return;
  try { await api('/api/mail/folders', {method: 'DELETE', body: {name: f.name}}); await loadFolders(); openFolder('INBOX'); } catch (e) { fail(e); }
});
$('#folder-empty').addEventListener('click', async () => {
  const f = folderInfo();
  if (!confirm(`Удалить навсегда все письма в папке «${f.title}»?`)) return;
  try { const r = await post('/api/mail/folders/empty', {folder: f.name}); toast(`Удалено писем: ${r.count}`); await refreshAll(); } catch (e) { fail(e); }
});

// ---------- список ----------
async function loadList() {
  const f = folderInfo();
  $('#list-title').textContent = f.title;
  const custom = !f.system;
  const emptyable = f.special === 'Trash' || f.special === 'Junk';
  $('#folder-tools').classList.toggle('hidden', !custom && !emptyable);
  $('#folder-rename').classList.toggle('hidden', !custom);
  $('#folder-delete').classList.toggle('hidden', !custom);
  $('#folder-empty').classList.toggle('hidden', !emptyable);
  $('#bulk-spam').title = f.special === 'Junk' ? 'Не спам' : 'В спам';
  $('#bulk-spam').dataset.bulk = f.special === 'Junk' ? 'notspam' : 'spam';
  const params = {folder: state.folder, page: state.page, q: $('#search').value.trim(), field: $('#search-field').value,
    unseen: $('#filter-unseen').checked ? 1 : 0, flagged: $('#filter-flagged').checked ? 1 : 0,
    threads: $('#threads-mode').checked ? 1 : 0};
  const d = await api(`/api/mail/messages?${q(params)}`);
  state.items = d.items;
  state.pages = d.pages;
  state.total = d.total;
  renderList();
}

function renderList() {
  const box = $('#messages');
  box.innerHTML = '';
  const outgoing = ['Sent', 'Drafts'].includes(folderInfo().special);
  if (!state.items.length) {
    box.innerHTML = `<div class="empty">${$('#search').value ? 'Ничего не найдено' : 'В этой папке нет писем'}</div>`;
  }
  for (const m of state.items) {
    const row = document.createElement('div');
    const uids = m.thread || [m.uid];
    const seen = m.thread ? !m.thread_unseen : m.flags.includes('\\Seen');
    const active = state.current && uids.includes(state.current.uid);
    row.className = `msg${seen ? '' : ' unread'}${active ? ' active' : ''}`;
    row.draggable = true;
    row.innerHTML = '<input type="checkbox" aria-label="Выбрать"><span class="who"></span><span class="date"></span><span class="subj"></span><span class="marks"></span>';
    const cb = $('input', row);
    cb.checked = uids.every((u) => state.selected.has(u));
    cb.addEventListener('click', (e) => { e.stopPropagation(); uids.forEach((u) => (cb.checked ? state.selected.add(u) : state.selected.delete(u))); });
    const who = m.participants && m.count > 1 ? m.participants : m.from;
    $('.who', row).textContent = outgoing ? `Кому: ${m.to.map(person).join(', ') || '—'}` : (who.map(person).join(', ') || '(без отправителя)');
    if (m.count > 1) $('.who', row).insertAdjacentHTML('beforeend', `<span class="count">${m.count}</span>`);
    $('.date', row).textContent = fmtDate(m.date);
    $('.subj', row).textContent = m.subject || '(без темы)';
    const marks = [];
    if (m.flagged || m.flags.includes('\\Flagged')) marks.push(`<span class="flag">${icon('star', 'fill')} важное</span>`);
    if (m.has_attachments) marks.push(`<span>${icon('clip')} вложение</span>`);
    if (m.flags.includes('\\Answered')) marks.push(`<span>${icon('reply')} отвечено</span>`);
    marks.push(`<span>${esc(fmtSize(m.size || 0))}</span>`);
    $('.marks', row).innerHTML = marks.join('');
    row.addEventListener('click', () => (folderInfo().special === 'Drafts' ? openCompose('draft', m.uid)
      : (m.count > 1 ? openThread(m.thread) : openMessage(m.uid))));
    row.addEventListener('dragstart', (e) => {
      const drag = state.selected.has(m.uid) ? [...state.selected] : uids;
      e.dataTransfer.setData('text/plain', JSON.stringify(drag));
    });
    box.appendChild(row);
  }
  $('#page-info').textContent = state.total ? `${(state.page - 1) * 50 + 1}–${Math.min(state.page * 50, state.total)} из ${state.total}` : '';
  $('#prev').disabled = state.page <= 1;
  $('#next').disabled = state.page >= state.pages;
  $('#select-all').checked = false;
}

$('#prev').addEventListener('click', () => { state.page--; loadList().catch(fail); });
$('#next').addEventListener('click', () => { state.page++; loadList().catch(fail); });
$('#refresh').addEventListener('click', () => refreshAll());
$('#search-form').addEventListener('submit', (e) => { e.preventDefault(); state.page = 1; loadList().catch(fail); });
$('#search-field').addEventListener('change', () => { if ($('#search').value) { state.page = 1; loadList().catch(fail); } });
$('#filter-unseen').addEventListener('change', () => { state.page = 1; loadList().catch(fail); });
$('#filter-flagged').addEventListener('change', () => { state.page = 1; loadList().catch(fail); });
try { $('#threads-mode').checked = localStorage.getItem('mr-threads') === '1'; } catch (e) { /* без хранилища */ }
$('#threads-mode').addEventListener('change', (e) => {
  try { localStorage.setItem('mr-threads', e.target.checked ? '1' : '0'); } catch (err) { /* без хранилища */ }
  state.page = 1;
  loadList().catch(fail);
});
$('#select-all').addEventListener('change', (e) => {
  state.selected = e.target.checked ? new Set(state.items.flatMap((m) => m.thread || [m.uid])) : new Set();
  renderList();
  $('#select-all').checked = e.target.checked;
});

async function bulk(action, target, uids) {
  uids = uids || [...state.selected];
  if (!uids.length && state.current) uids = [state.current.uid];
  if (!uids.length) return toast('Выберите письма');
  const f = folderInfo();
  if (action === 'delete' && f.special === 'Trash' && !confirm(`Удалить навсегда (${uids.length})?`)) return;
  try {
    await post('/api/mail/messages/action', {folder: state.folder, uids, action, target});
    state.selected.clear();
    if (['delete', 'move', 'spam', 'notspam'].includes(action) && state.current && uids.includes(state.current.uid)) closeReader();
    await refreshAll();
    if (action === 'spam') toast('Перенесено в «Спам»');
  } catch (e) { fail(e); }
}
$$('[data-bulk]').forEach((b) => b.addEventListener('click', () => bulk(b.dataset.bulk)));
$('#bulk-move').addEventListener('change', (e) => { if (e.target.value) bulk('move', e.target.value); e.target.value = ''; });

async function refreshAll() {
  await Promise.all([loadFolders(), loadList()]).catch(fail);
}

// ---------- чтение ----------
function closeReader() {
  state.current = null;
  $('#reader-view').classList.add('hidden');
  $('#reader-view').innerHTML = '';
  $('#reader-empty').classList.remove('hidden');
}

function linkify(text, parent) {
  const re = /(https?:\/\/[^\s<>"']+[^\s<>"'.,;:!?)\]])/g;
  let last = 0;
  for (const match of text.matchAll(re)) {
    parent.appendChild(document.createTextNode(text.slice(last, match.index)));
    const a = document.createElement('a');
    a.href = match[0];
    a.textContent = match[0];
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    parent.appendChild(a);
    last = match.index + match[0].length;
  }
  parent.appendChild(document.createTextNode(text.slice(last)));
}

async function openMessage(uid) {
  try {
    const m = await api(`/api/mail/message?${q({folder: state.folder, uid})}`);
    state.current = m;
    state.images = false;
    renderMessage();
    setView('reader');
    const row = state.items.find((x) => x.uid === uid);
    if (row && !row.flags.includes('\\Seen')) { row.flags.push('\\Seen'); loadFolders().catch(() => {}); }
    renderList();
  } catch (e) { fail(e); }
}

const ACTIONS = (m, f) => `<div class="reader-actions">
      <button class="btn" data-act="reply">${icon('reply')} Ответить</button><button class="btn" data-act="replyall">${icon('replyall')} Всем</button>
      <button class="btn" data-act="forward">${icon('forward')} Переслать</button>
      <button class="btn" data-act="flag">${icon('star', m.flags.includes('\\Flagged') ? 'fill' : '')} ${m.flags.includes('\\Flagged') ? 'Не важное' : 'Важное'}</button>
      <button class="btn" data-act="unread">${icon('dot')} Не прочитано</button>
      <button class="btn" data-act="${f.special === 'Junk' ? 'notspam' : 'spam'}">${icon('ban')} ${f.special === 'Junk' ? 'Не спам' : 'Спам'}</button>
      <button class="btn danger" data-act="delete">${icon('trash')} Удалить</button>
      <button class="btn" data-act="raw">${icon('code')} Исходник</button></div>`;

function renderMeta(m, dl) {
  for (const [label, value] of [['От', people(m.from)], ['Кому', people(m.to)], ['Копия', people(m.cc)], ['Дата', fmtDate(m.date, true)]]) {
    if (!value) continue;
    const dt = document.createElement('dt'); dt.textContent = label;
    const dd = document.createElement('dd'); dd.textContent = value;
    dl.append(dt, dd);
  }
}

function renderBody(m, container, images, rerender) {
  if (m.spam) container.insertAdjacentHTML('beforeend', '<div class="banner danger">Письмо помечено как спам. Не переходите по ссылкам и не открывайте вложения, если не уверены в отправителе.</div>');
  if (m.has_html) {
    if (m.remote_images && !images) {
      const banner = document.createElement('div');
      banner.className = 'banner warn';
      banner.innerHTML = '<span>Внешние изображения скрыты: они позволяют отправителю узнать, что вы открыли письмо.</span><button class="btn">Показать изображения</button>';
      $('button', banner).addEventListener('click', rerender);
      container.appendChild(banner);
    }
    const frame = document.createElement('iframe');
    frame.setAttribute('sandbox', 'allow-popups allow-popups-to-escape-sandbox');
    frame.setAttribute('referrerpolicy', 'no-referrer');
    frame.title = 'Текст письма';
    frame.src = `/api/mail/message/html?${q({folder: state.folder, uid: m.uid, images: images ? 1 : 0})}`;
    container.appendChild(frame);
  } else {
    const pre = document.createElement('pre');
    linkify(m.text || '', pre);
    container.appendChild(pre);
  }
}

function renderAttachments(m, att) {
  if (!m.attachments.length) return;
  att.classList.remove('hidden');
  for (const a of m.attachments) {
    const url = `/api/mail/attachment?${q({folder: state.folder, uid: m.uid, index: a.index})}`;
    const link = document.createElement('a');
    link.className = 'attachment';
    link.href = url;
    link.innerHTML = icon('clip');
    link.append(` ${a.filename} · ${fmtSize(a.size)}`);
    link.title = `Скачать ${a.filename}`;
    if (!a.preview) { att.appendChild(link); continue; }
    const wrap = document.createElement('span');
    wrap.className = 'attachment-wrap';
    const view = document.createElement('button');
    view.type = 'button';
    view.innerHTML = `${icon('eye')} Просмотр`;
    view.addEventListener('click', () => openPreview(a, url));
    wrap.append(link, view);
    att.appendChild(wrap);
  }
}

async function openPreview(a, url) {
  const dlg = $('#preview-dlg');
  const body = $('#preview-body');
  $('#preview-title').textContent = a.filename;
  $('#preview-download').href = url;
  body.innerHTML = '';
  const inline = `${url}&inline=1`;
  if (a.preview === 'image') {
    const img = document.createElement('img');
    img.src = inline;
    img.alt = a.filename;
    body.appendChild(img);
  } else if (a.preview === 'pdf') {
    const frame = document.createElement('iframe');
    frame.src = inline;
    frame.title = a.filename;
    body.appendChild(frame);
  } else {
    const pre = document.createElement('pre');
    pre.textContent = 'Загрузка…';
    body.appendChild(pre);
    try {
      const r = await fetch(inline);
      const text = await r.text();
      pre.textContent = text.length > 500000 ? `${text.slice(0, 500000)}\n…(файл обрезан, скачайте целиком)` : text;
    } catch (e) { pre.textContent = 'Не удалось загрузить файл'; }
  }
  dlg.showModal();
}
$('#preview-close').addEventListener('click', () => { $('#preview-dlg').close(); $('#preview-body').innerHTML = ''; });

function renderMessage() {
  const m = state.current;
  const view = $('#reader-view');
  $('#reader-empty').classList.add('hidden');
  view.classList.remove('hidden');
  view.innerHTML = `<div class="reader-head"><h1></h1><dl class="reader-meta"></dl>${ACTIONS(m, folderInfo())}</div>
    <div class="reader-body"></div><div class="attachments hidden"></div>`;
  $('h1', view).textContent = m.subject || '(без темы)';
  renderMeta(m, $('.reader-meta', view));
  renderBody(m, $('.reader-body', view), state.images, () => { state.images = true; renderMessage(); });
  renderAttachments(m, $('.attachments', view));
  $$('[data-act]', view).forEach((b) => b.addEventListener('click', () => readerAction(b.dataset.act)));
}

async function openThread(uids) {
  try {
    const d = await api(`/api/mail/thread?${q({folder: state.folder, uids: uids.join(',')})}`);
    if (!d.items.length) return;
    const last = d.items[d.items.length - 1];
    state.current = last;
    state.thread = d.items;
    state.images = false;
    const view = $('#reader-view');
    $('#reader-empty').classList.add('hidden');
    view.classList.remove('hidden');
    view.innerHTML = `<div class="reader-head"><h1></h1><p class="small muted">Писем в цепочке: ${d.items.length}. Действия ниже относятся к последнему письму.</p>${ACTIONS(last, folderInfo())}</div>
      <div class="thread-list"></div>`;
    $('h1', view).textContent = d.items[0].subject || '(без темы)';
    const list = $('.thread-list', view);
    d.items.forEach((m, i) => {
      const item = document.createElement('article');
      item.className = `thread-item${i === d.items.length - 1 ? '' : ' collapsed'}`;
      item.innerHTML = '<header><div><b class="who"></b><div class="snippet"></div></div><span class="small muted date"></span></header><div class="thread-content"><dl class="reader-meta"></dl><div class="body"></div><div class="attachments hidden"></div></div>';
      $('.who', item).textContent = people(m.from) || '(без отправителя)';
      $('.date', item).textContent = fmtDate(m.date, true);
      $('.snippet', item).textContent = (m.text || '').replace(/\s+/g, ' ').slice(0, 160);
      let rendered = false;
      const render = (images) => {
        const body = $('.body', item);
        body.innerHTML = '';
        renderBody(m, body, images, () => render(true));
        if (!rendered) { renderMeta(m, $('.reader-meta', item)); renderAttachments(m, $('.attachments', item)); }
        rendered = true;
      };
      $('header', item).addEventListener('click', () => {
        item.classList.toggle('collapsed');
        if (!item.classList.contains('collapsed') && !rendered) render(false);
      });
      if (i === d.items.length - 1) render(false);
      list.appendChild(item);
    });
    $$('[data-act]', view).forEach((b) => b.addEventListener('click', () => readerAction(b.dataset.act)));
    setView('reader');
    loadFolders().catch(() => {});
    const row = state.items.find((x) => x.thread && x.thread.includes(last.uid));
    if (row) row.thread_unseen = 0;
    renderList();
  } catch (e) { fail(e); }
}

function readerAction(act) {
  const m = state.current;
  if (!m) return;
  if (['reply', 'replyall', 'forward'].includes(act)) return openCompose(act, m.uid);
  if (act === 'raw') return window.open(`/api/mail/message/raw?${q({folder: state.folder, uid: m.uid})}`, '_blank', 'noopener');
  if (act === 'flag') return bulk(m.flags.includes('\\Flagged') ? 'unflag' : 'flag', null, [m.uid]).then(() => openMessage(m.uid));
  if (act === 'unread') return bulk('unread', null, [m.uid]).then(() => { closeReader(); setView('list'); });
  return bulk(act, null, [m.uid]).then(() => setView('list'));
}

// ---------- написание ----------
const composeForm = $('#compose-form');
const editor = $('#editor');
const ALLOWED = new Set(['P', 'BR', 'DIV', 'SPAN', 'B', 'STRONG', 'I', 'EM', 'U', 'S', 'STRIKE', 'UL', 'OL', 'LI',
  'BLOCKQUOTE', 'A', 'IMG', 'H1', 'H2', 'H3', 'PRE', 'CODE', 'HR', 'SUB', 'SUP']);
// Очистка HTML для редактора: DOMParser не исполняет скрипты; остаются только безопасные теги и атрибуты.
function cleanHtml(html) {
  const doc = new DOMParser().parseFromString(`<body>${html}</body>`, 'text/html');
  const walk = (node, out) => {
    for (const child of [...node.childNodes]) {
      if (child.nodeType === Node.TEXT_NODE) { out.appendChild(document.createTextNode(child.textContent)); continue; }
      if (child.nodeType !== Node.ELEMENT_NODE) continue;
      if (['SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'SVG', 'TITLE', 'HEAD'].includes(child.tagName)) continue;
      if (!ALLOWED.has(child.tagName)) { walk(child, out); continue; }
      const el = document.createElement(child.tagName);
      if (child.tagName === 'A' && /^(https?:|mailto:)/i.test(child.getAttribute('href') || '')) el.setAttribute('href', child.getAttribute('href'));
      if (child.tagName === 'IMG') {
        const src = child.getAttribute('src') || '';
        if (!/^data:image\/(png|jpeg|gif|webp);base64,/i.test(src)) continue;
        el.setAttribute('src', src);
      }
      walk(child, el);
      out.appendChild(el);
    }
    return out;
  };
  const box = document.createElement('div');
  walk(doc.body, box);
  return box.innerHTML;
}
const textToHtml = (text) => esc(text).replace(/\n/g, '<br>');
const isPlain = () => $('#plain-mode').checked;
function setPlain(on, convert = true) {
  $('#plain-mode').checked = on;
  composeForm.classList.toggle('plain', on);
  if (!convert) return;
  if (on) composeForm.body.value = editor.innerText;
  else editor.innerHTML = textToHtml(composeForm.body.value);
}
$('#plain-mode').addEventListener('change', (e) => {
  setPlain(e.target.checked);
  try { localStorage.setItem('mr-plain', e.target.checked ? '1' : '0'); } catch (err) { /* без хранилища */ }
});
$$('#editor-bar [data-cmd]').forEach((b) => {
  b.addEventListener('mousedown', (e) => e.preventDefault());
  b.addEventListener('click', () => {
    editor.focus();
    const cmd = b.dataset.cmd;
    if (cmd === 'quote') document.execCommand('formatBlock', false, 'blockquote');
    else if (cmd === 'link') {
      const url = prompt('Адрес ссылки (https://… или mailto:…):', 'https://');
      if (url && /^(https?:\/\/|mailto:)/i.test(url)) document.execCommand('createLink', false, url);
      else if (url) toast('Ссылка должна начинаться с https:// или mailto:', true);
    } else document.execCommand(cmd, false, null);
  });
});
$('#editor-image').addEventListener('change', (e) => {
  const file = e.target.files[0];
  e.target.value = '';
  if (!file) return;
  if (file.size > 5 * 1048576) return toast('Картинка в тексте — до 5 МБ; большие файлы прикладывайте вложением', true);
  const reader = new FileReader();
  reader.onload = () => { editor.focus(); document.execCommand('insertImage', false, reader.result); };
  reader.readAsDataURL(file);
});
editor.addEventListener('paste', (e) => {
  const html = e.clipboardData.getData('text/html');
  const text = e.clipboardData.getData('text/plain');
  e.preventDefault();
  if (html) document.execCommand('insertHTML', false, cleanHtml(html));
  else document.execCommand('insertText', false, text);
});
editor.addEventListener('drop', (e) => {
  if (e.dataTransfer.files.length) { e.preventDefault(); state.compose.files.push(...e.dataTransfer.files); renderFiles(); }
});
function resetCompose() {
  composeForm.reset();
  state.compose = {mode: 'new', files: [], keep: [], source: null, draftUid: null, reply: null, in_reply_to: '', references: ''};
  $('#compose-files').innerHTML = '';
  $('#compose-error').classList.add('hidden');
  $('#compose-status').textContent = '';
  $('#bcc-row').classList.add('hidden');
}

async function openCompose(mode = 'new', uid = null) {
  resetCompose();
  const c = state.compose;
  c.mode = mode;
  const titles = {new: 'Новое письмо', reply: 'Ответ', replyall: 'Ответ всем', forward: 'Пересылка', draft: 'Черновик'};
  $('#compose-title').textContent = titles[mode] || 'Письмо';
  const signature = state.me.signature ? `\n\n-- \n${state.me.signature}` : '';
  const signatureHtml = state.me.signature ? `<p><br></p><p>-- <br>${textToHtml(state.me.signature)}</p>` : '<p><br></p>';
  let plainPref = false;
  try { plainPref = localStorage.getItem('mr-plain') === '1'; } catch (e) { /* без хранилища */ }
  if (uid) {
    try {
      const d = await api(`/api/mail/compose?${q({folder: state.folder, uid, mode})}`);
      composeForm.to.value = d.to || '';
      composeForm.cc.value = d.cc || '';
      if (d.bcc) { composeForm.bcc.value = d.bcc; $('#bcc-row').classList.remove('hidden'); }
      composeForm.subject.value = d.subject || '';
      composeForm.body.value = mode === 'draft' ? d.body : signature + d.body;
      editor.innerHTML = cleanHtml(d.body_html ? (mode === 'draft' ? d.body_html : signatureHtml + d.body_html) : textToHtml(composeForm.body.value));
      setPlain(mode === 'draft' ? !d.body_html : plainPref, false);
      c.in_reply_to = d.in_reply_to;
      c.references = d.references;
      c.source = d.source;
      if (mode === 'draft') c.draftUid = uid;
      if (mode === 'reply' || mode === 'replyall') c.reply = d.source;
      c.keep = (d.attachments || []).map((a) => ({...a, kept: true}));
    } catch (e) { return fail(e); }
  } else {
    composeForm.body.value = signature;
    editor.innerHTML = signatureHtml;
    setPlain(plainPref, false);
  }
  renderFiles();
  $('#compose-dlg').showModal();
  if (!composeForm.to.value) composeForm.to.focus();
  else if (isPlain()) { composeForm.body.focus(); composeForm.body.setSelectionRange(0, 0); }
  else {
    editor.focus();
    const range = document.createRange();
    range.setStart(editor, 0);
    range.collapse(true);
    getSelection().removeAllRanges();
    getSelection().addRange(range);
  }
}
$('#compose-btn').addEventListener('click', () => openCompose('new'));
$('#show-bcc').addEventListener('click', () => $('#bcc-row').classList.remove('hidden'));

function renderFiles() {
  const box = $('#compose-files');
  box.innerHTML = '';
  const all = [...state.compose.keep.map((a, i) => ({name: a.filename, size: a.size, kind: 'keep', i})),
    ...state.compose.files.map((f, i) => ({name: f.name, size: f.size, kind: 'file', i}))];
  for (const item of all) {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.innerHTML = icon('clip');
    chip.append(` ${item.name} · ${fmtSize(item.size)}`);
    const x = document.createElement('button');
    x.type = 'button';
    x.innerHTML = icon('close');
    x.title = 'Убрать';
    x.addEventListener('click', () => { (item.kind === 'keep' ? state.compose.keep : state.compose.files).splice(item.i, 1); renderFiles(); });
    chip.appendChild(x);
    box.appendChild(chip);
  }
  const total = all.reduce((s, x) => s + x.size, 0);
  const limit = (state.me?.limits?.attach_mb || 20) * 1048576;
  $('#compose-status').textContent = total ? `Вложения: ${fmtSize(total)}${total > limit ? ' — больше лимита!' : ''}` : '';
}
$('#compose-attach').addEventListener('change', (e) => {
  state.compose.files.push(...e.target.files);
  e.target.value = '';
  renderFiles();
});

function composeData() {
  const c = state.compose;
  const fd = new FormData();
  for (const key of ['to', 'cc', 'bcc', 'subject']) fd.append(key, composeForm[key].value);
  if (isPlain()) fd.append('body', composeForm.body.value);
  else { fd.append('body', editor.innerText); fd.append('body_html', editor.innerHTML); }
  fd.append('in_reply_to', c.in_reply_to || '');
  fd.append('references', c.references || '');
  if (c.source && c.keep.length) {
    fd.append('source_folder', c.source.folder);
    fd.append('source_uid', c.source.uid);
    fd.append('keep_attachments', c.keep.map((a) => a.index).join(','));
  }
  if (c.reply) { fd.append('reply_folder', c.reply.folder); fd.append('reply_uid', c.reply.uid); }
  if (c.draftUid) fd.append('draft_uid', c.draftUid);
  for (const f of c.files) fd.append('files', f, f.name);
  return fd;
}

composeForm.addEventListener('submit', async (e) => {
  if (e.submitter && e.submitter.value === 'cancel') return;
  e.preventDefault();
  const button = $('#compose-send');
  button.disabled = true;
  $('#compose-error').classList.add('hidden');
  $('#compose-status').textContent = 'Отправка…';
  try {
    const r = await api('/api/mail/send', {method: 'POST', body: composeData()});
    $('#compose-dlg').close();
    toast(r.refused && r.refused.length ? `Отправлено, но отклонены: ${r.refused.join(', ')}` : 'Письмо отправлено', Boolean(r.refused && r.refused.length));
    if (r.warnings && r.warnings.length) toast(r.warnings.join('; '), true);
    refreshAll();
  } catch (err) {
    $('#compose-error').textContent = err.message;
    $('#compose-error').classList.remove('hidden');
    $('#compose-status').textContent = '';
  } finally { button.disabled = false; }
});

$('#compose-draft').addEventListener('click', async () => {
  try {
    const r = await api('/api/mail/draft', {method: 'POST', body: composeData()});
    state.compose.draftUid = r.uid;
    // Вложения уже в черновике: дальше они берутся оттуда.
    if (r.uid) {
      const drafts = state.folders.find((f) => f.special === 'Drafts');
      state.compose.source = {folder: drafts ? drafts.name : 'Drafts', uid: r.uid};
      const d = await api(`/api/mail/compose?${q({folder: state.compose.source.folder, uid: r.uid, mode: 'draft'})}`);
      state.compose.keep = d.attachments || [];
      state.compose.files = [];
      renderFiles();
    }
    $('#compose-status').textContent = `Черновик сохранён ${new Date().toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'})}`;
    loadFolders().catch(() => {});
  } catch (e) { fail(e); }
});

// автодополнение адресов
let suggestBox = null;
function closeSuggest() { suggestBox?.remove(); suggestBox = null; }
$$('[data-suggest]').forEach((input) => {
  input.addEventListener('input', async () => {
    const token = input.value.split(',').pop().trim();
    closeSuggest();
    if (token.length < 2) return;
    const d = await api(`/api/mail/contacts?${q({q: token})}`).catch(() => ({items: []}));
    if (!d.items.length) return;
    suggestBox = document.createElement('div');
    suggestBox.className = 'suggest';
    for (const c of d.items) {
      const b = document.createElement('button');
      b.type = 'button';
      b.textContent = c.name ? `${c.name} <${c.email}>` : c.email;
      b.addEventListener('mousedown', (e) => {
        e.preventDefault();
        const parts = input.value.split(',');
        parts[parts.length - 1] = ` ${c.name ? `"${c.name.replace(/"/g, '')}" <${c.email}>` : c.email}`;
        input.value = parts.join(',').replace(/^\s+/, '') + ', ';
        closeSuggest();
        input.focus();
      });
      suggestBox.appendChild(b);
    }
    input.parentElement.appendChild(suggestBox);
  });
  input.addEventListener('blur', () => setTimeout(closeSuggest, 150));
});

// ---------- настройки ----------
const sform = $('#settings-form');
function settingsTab(name) {
  $$('#settings-tabs .tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $$('[data-tabpage]', sform).forEach((p) => p.classList.toggle('hidden', p.dataset.tabpage !== name));
  $('#settings-save').classList.toggle('hidden', ['password', 'contacts', 'connect'].includes(name));
  if (name === 'contacts') loadContacts().catch(fail);
}
$$('#settings-tabs .tab').forEach((t) => t.addEventListener('click', () => settingsTab(t.dataset.tab)));
$('#settings-close').addEventListener('click', () => $('#settings-dlg').close());
$('#settings-cancel').addEventListener('click', () => $('#settings-dlg').close());

$('#open-settings').addEventListener('click', async () => {
  try {
    const s = await api('/api/mail/settings');
    sform.display_name.value = s.display_name || '';
    sform.signature.value = s.signature || '';
    const v = s.vacation || {};
    sform.vac_enabled.checked = Boolean(v.enabled); sform.vac_start.value = v.start || ''; sform.vac_end.value = v.end || '';
    sform.vac_subject.value = v.subject || ''; sform.vac_days.value = v.days || 7; sform.vac_text.value = v.text || '';
    const f = s.forward || {};
    sform.fwd_enabled.checked = Boolean(f.enabled); sform.fwd_address.value = f.address || ''; sform.fwd_keep.checked = f.keep !== false;
    state.filters = (s.filters || []).map((x) => ({...x}));
    renderFilters();
    $('#session-list').innerHTML = '<b>Активные сеансы:</b>' + (s.sessions || []).map((x) =>
      `<div>${x.current ? '● текущий — ' : ''}${esc(x.ip)} · ${esc(new Date(x.last_seen * 1000).toLocaleString('ru-RU'))} · <span class="muted">${esc(x.user_agent.slice(0, 80))}</span></div>`).join('');
    const c = state.me.client;
    $('#connect-info').innerHTML = `<dl class="kv"><dt>Входящая почта (IMAP)</dt><dd><code>${esc(c.imap)}</code></dd>
      <dt>Исходящая (SMTP)</dt><dd><code>${esc(c.smtp)}</code>, авторизация обязательна</dd>
      <dt>Логин</dt><dd><code>${esc(c.login)}</code></dd><dt>Пароль</dt><dd>пароль от этого ящика</dd></dl>
      ${c.ca ? '<p class="small">Сервер использует собственный сертификат. Чтобы почтовая программа и браузер не показывали предупреждения, установите <a href="/mail/ca.crt">корневой сертификат</a> как доверенный (Windows: двойной щелчок → «Установить» → «Доверенные корневые центры»; Android: Настройки → Безопасность → Установить сертификат; Thunderbird: Настройки → Сертификаты → Импортировать).</p>' : ''}`;
    $('#settings-error').classList.add('hidden');
    settingsTab('profile');
    $('#settings-dlg').showModal();
  } catch (e) { fail(e); }
});

function renderFilters() {
  const list = $('#filter-list');
  list.innerHTML = state.filters.length ? '' : '<p class="small muted">Правил пока нет.</p>';
  const folderOptions = state.folders.filter((f) => f.special !== 'Drafts' && f.special !== 'Sent');
  state.filters.forEach((rule, i) => {
    const row = document.createElement('div');
    row.className = 'rule';
    row.innerHTML = `<input type="checkbox" title="Включено"><select data-k="field"><option value="from">От кого</option><option value="to">Кому/копия</option><option value="subject">Тема</option></select>
      <input data-k="value" placeholder="содержит…"><select data-k="action"><option value="move">переместить в</option><option value="read">пометить прочитанным</option><option value="delete">удалить</option></select>
      <select data-k="folder"></select><button class="icon" type="button" title="Удалить правило">${icon('close')}</button>`;
    const fsel = $('[data-k="folder"]', row);
    for (const f of folderOptions) { const o = document.createElement('option'); o.value = f.name; o.textContent = f.title; fsel.appendChild(o); }
    $('input[type=checkbox]', row).checked = rule.enabled !== false;
    $('[data-k="field"]', row).value = rule.field || 'from';
    $('[data-k="value"]', row).value = rule.value || '';
    $('[data-k="action"]', row).value = rule.action || 'move';
    fsel.value = rule.folder || (folderOptions[0]?.name || '');
    fsel.classList.toggle('hidden', (rule.action || 'move') !== 'move');
    row.addEventListener('input', () => {
      rule.enabled = $('input[type=checkbox]', row).checked;
      rule.field = $('[data-k="field"]', row).value;
      rule.value = $('[data-k="value"]', row).value;
      rule.action = $('[data-k="action"]', row).value;
      rule.folder = fsel.value;
      fsel.classList.toggle('hidden', rule.action !== 'move');
    });
    $('button', row).addEventListener('click', () => { state.filters.splice(i, 1); renderFilters(); });
    list.appendChild(row);
  });
}
$('#filter-add').addEventListener('click', () => {
  state.filters.push({field: 'from', value: '', action: 'move', folder: state.folders.find((f) => !f.system)?.name || 'INBOX', enabled: true});
  renderFilters();
});

$('#settings-save').addEventListener('click', async () => {
  const body = {
    display_name: sform.display_name.value, signature: sform.signature.value,
    vacation: {enabled: sform.vac_enabled.checked, start: sform.vac_start.value, end: sform.vac_end.value,
      subject: sform.vac_subject.value, days: Number(sform.vac_days.value) || 7, text: sform.vac_text.value},
    forward: {enabled: sform.fwd_enabled.checked, address: sform.fwd_address.value.trim(), keep: sform.fwd_keep.checked},
    filters: state.filters,
  };
  try {
    await api('/api/mail/settings', {method: 'PUT', body});
    $('#settings-dlg').close();
    toast('Настройки сохранены');
    await loadMe();
  } catch (e) {
    $('#settings-error').textContent = e.message;
    $('#settings-error').classList.remove('hidden');
  }
});

$('#password-save').addEventListener('click', async () => {
  try {
    await post('/api/mail/password', {current_password: sform.current_password.value, new_password: sform.new_password.value});
    sform.current_password.value = '';
    sform.new_password.value = '';
    toast('Пароль изменён. Укажите новый пароль в почтовых программах.');
  } catch (e) {
    $('#settings-error').textContent = e.message;
    $('#settings-error').classList.remove('hidden');
  }
});

async function loadContacts() {
  const d = await api('/api/mail/contacts');
  const box = $('#contact-list');
  box.innerHTML = d.items.length ? '' : '<p class="small muted">Адреса, на которые вы пишете, добавляются сюда автоматически.</p>';
  for (const c of d.items) {
    const row = document.createElement('div');
    row.className = 'msg';
    row.innerHTML = `<span></span><span class="who"></span><button class="icon" type="button" title="Удалить">${icon('close')}</button><span class="subj"></span>`;
    $('.who', row).textContent = c.name || c.email;
    $('.subj', row).textContent = c.email;
    $('button', row).addEventListener('click', async () => { await api(`/api/mail/contacts/${c.id}`, {method: 'DELETE'}).catch(fail); loadContacts(); });
    row.addEventListener('dblclick', () => { $('#settings-dlg').close(); openCompose('new').then(() => { composeForm.to.value = c.email; }); });
    box.appendChild(row);
  }
}
$('#contact-add').addEventListener('click', async () => {
  try {
    await post('/api/mail/contacts', {email: $('#contact-email').value.trim(), name: $('#contact-name').value.trim()});
    $('#contact-email').value = '';
    $('#contact-name').value = '';
    loadContacts();
  } catch (e) { fail(e); }
});

// ---------- выход и клавиши ----------
$('#logout').addEventListener('click', async () => {
  await post('/api/mail/logout').catch(() => {});
  location.href = '/mail/login';
});

document.addEventListener('keydown', (e) => {
  if (e.target.closest('input, textarea, select') || document.querySelector('dialog[open]') || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === 'c') { e.preventDefault(); openCompose('new'); }
  else if (e.key === 'r' && state.current) { e.preventDefault(); openCompose('reply', state.current.uid); }
  else if (e.key === '/') { e.preventDefault(); setView('list'); $('#search').focus(); }
  else if (e.key === 'Delete') { e.preventDefault(); bulk('delete'); }
  else if (e.key === 'Escape' && state.current) { closeReader(); setView('list'); }
});

// Мгновенно: сервер держит IMAP IDLE и присылает событие при новых письмах.
let changeTimer = null;
function inboxUnseen() { return state.folders.find((f) => f.special === 'INBOX')?.unseen || 0; }
async function onMailChange() {
  const before = inboxUnseen();
  await loadFolders().catch(() => {});
  if (state.folder === 'INBOX' && state.page === 1 && !state.selected.size && !$('#search').value) loadList().catch(() => {});
  const after = inboxUnseen();
  if (after > before) desktopNotify(after - before);
}
function startEvents() {
  if (!window.EventSource) return;
  const es = new EventSource('/api/mail/events');
  es.addEventListener('change', () => { clearTimeout(changeTimer); changeTimer = setTimeout(onMailChange, 400); });
  es.addEventListener('logout', () => { es.close(); location.href = '/mail/login'; });
}
function notifyEnabled() {
  try { return localStorage.getItem('mr-notify') === '1' && window.Notification && Notification.permission === 'granted'; } catch (e) { return false; }
}
function desktopNotify(count) {
  if (!notifyEnabled() || !document.hidden) return;
  const n = new Notification('Новая почта', {body: count === 1 ? 'Пришло новое письмо' : `Новых писем: ${count}`, tag: 'mailroom-new'});
  n.onclick = () => { window.focus(); openFolder('INBOX'); n.close(); };
}
function renderNotifyState() {
  $('#notify-state').textContent = !window.Notification ? 'браузер не поддерживает уведомления'
    : notifyEnabled() ? 'включены' : Notification.permission === 'denied' ? 'запрещены в настройках браузера' : 'выключены';
  $('#notify-toggle').textContent = notifyEnabled() ? 'Выключить уведомления на рабочем столе' : 'Уведомлять о новых письмах на рабочем столе';
}
$('#notify-toggle').addEventListener('click', async () => {
  if (!window.Notification) return;
  if (notifyEnabled()) { try { localStorage.setItem('mr-notify', '0'); } catch (e) { /* */ } return renderNotifyState(); }
  const permission = await Notification.requestPermission();
  try { localStorage.setItem('mr-notify', permission === 'granted' ? '1' : '0'); } catch (e) { /* */ }
  renderNotifyState();
});

// Запасная проверка раз в 5 минут — если поток событий оборвался.
setInterval(() => {
  if (document.hidden || document.querySelector('dialog[open]')) return;
  loadFolders().catch(() => {});
  if (state.page === 1 && !state.selected.size && !$('#search').value) loadList().catch(() => {});
}, 300000);

(async () => {
  try {
    await loadMe();
    await loadFolders();
    await loadList();
    renderNotifyState();
    startEvents();
  } catch (e) { fail(e); }
})();
