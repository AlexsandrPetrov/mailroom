const sections = ['overview', 'queue', 'collectors', 'domains', 'mailboxes', 'config', 'journal', 'logs', 'security', 'users', 'diagnostics', 'setup', 'settings'];
const titleMap = {overview: 'Обзор системы', queue: 'Очередь доставки', collectors: 'Сборщики почты', domains: 'Домены', mailboxes: 'Почтовые ящики', config: 'Конфигурация', journal: 'Журнал действий', logs: 'Логи сервисов', security: 'Безопасность', users: 'Пользователи', diagnostics: 'Диагностика', setup: 'Установка шлюза', settings: 'Настройки сервера'};
const $ = (selector) => document.querySelector(selector);
let csrfToken = '';

function showSection(name) {
  sections.forEach((section) => $(`#section-${section}`).classList.toggle('hidden', section !== name));
  document.querySelectorAll('.nav-item').forEach((item) => item.classList.toggle('active', item.dataset.section === name));
  $('#page-title').textContent = titleMap[name];
  if (name === 'queue') loadQueue();
  if (name === 'collectors') loadCollectors();
  if (name === 'domains') loadDomains();
  if (name === 'mailboxes') loadMailboxes();
  if (name === 'config') loadConfig();
  if (name === 'journal') loadJournal();
  if (name === 'logs') loadLogs();
  if (name === 'security') loadSecurity();
  if (name === 'users') loadUsers();
  if (name === 'settings') loadSettings();
}

async function getJSON(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function sendJSON(path, options = {}) {
  const headers = {'Content-Type': 'application/json', ...(options.headers || {}), 'X-CSRF-Token': csrfToken};
  return fetch(path, {...options, headers});
}

function serviceMarkup(service) {
  const active = service.state === 'active';
  return `<div class="service-row"><span>${service.name}</span><span class="service-state ${active ? '' : 'off'}">${active ? '● active' : service.state}</span></div>`;
}

async function loadOverview() {
  try {
    const data = await getJSON('/api/overview');
    $('#host-name').textContent = data.host;
    $('#metrics').innerHTML = `<div class="metric"><div class="metric-label">ОЧЕРЕДЬ</div><div class="metric-value">${data.queue.count}<small>сообщений</small></div></div><div class="metric"><div class="metric-label">УЗЕЛ</div><div class="metric-value">${data.host.slice(0, 12)}<small>hostname</small></div></div><div class="metric"><div class="metric-label">РЕЖИМ</div><div class="metric-value">MVP<small>только чтение</small></div></div>`;
    $('#services').innerHTML = data.services.map(serviceMarkup).join('');
    $('#updated').textContent = `обновлено ${new Date(data.timestamp).toLocaleTimeString('ru-RU')}`;
    if (!data.queue.available) $('#notice').textContent = `Postfix недоступен: ${data.queue.raw || 'проверьте установку сервиса'}`;
    $('#notice').classList.toggle('hidden', data.queue.available);
  } catch (error) {
    $('#notice').textContent = `Не удалось получить состояние узла: ${error.message}`;
    $('#notice').classList.remove('hidden');
  }
}

async function loadQueue() {
  const data = await getJSON('/api/overview');
  $('#queue-large').innerHTML = `${data.queue.count}<small> сообщений в очереди</small>`;
  $('#queue-raw').textContent = data.queue.raw || 'Очередь пуста или Postfix недоступен.';
}

async function loadCollectors() {
  const data = await getJSON('/api/collectors');
  $('#collectors').innerHTML = data.items.map((item) => `<article class="collector"><div class="eyebrow">${item.protocol}</div><div class="collector-title">${item.name}</div><div class="collector-meta"><div>Назначение <span>${item.destination}</span></div><div>Расписание <span>${item.schedule}</span></div></div><span class="tag">${item.state}</span></article>`).join('');
}

async function loadConfig() {
  const data = await getJSON('/api/config');
  $('#config-list').innerHTML = data.available ? data.values.map((item) => `<div class="config-row"><span>${item.key}</span><span>${item.value}</span></div>`).join('') : `<p class="muted">${data.error}</p>`;
}

function formatDate(value) {
  return new Date(value).toLocaleString('ru-RU', {dateStyle: 'short', timeStyle: 'short'});
}

async function loadDomains() {
  const data = await getJSON('/api/domains');
  $('#domains-table').innerHTML = data.items.map((item) => `<tr><td><strong>${item.name}</strong></td><td><span class="status-pill">${item.status}</span></td><td>${item.mailbox_count}</td><td>${item.quota_mb.toLocaleString('ru-RU')} МБ</td><td><button class="danger-link" data-delete-domain="${item.id}">Удалить</button></td></tr>`).join('');
  document.querySelectorAll('[data-delete-domain]').forEach((button) => button.addEventListener('click', () => deleteDomain(button.dataset.deleteDomain)));
}

async function loadMailboxes() {
  const data = await getJSON('/api/mailboxes');
  $('#mailboxes-table').innerHTML = data.items.map((item) => `<tr><td><strong>${item.localpart}@${item.domain_name}</strong></td><td><span class="status-pill">${item.status}</span></td><td>${item.quota_mb.toLocaleString('ru-RU')} МБ</td><td>${formatDate(item.created_at)}</td><td><button class="action-link" data-reset-mailbox="${item.id}">Сбросить пароль</button> <button class="danger-link" data-delete-mailbox="${item.id}">Удалить</button></td></tr>`).join('');
  document.querySelectorAll('[data-delete-mailbox]').forEach((button) => button.addEventListener('click', () => deleteMailbox(button.dataset.deleteMailbox)));
  document.querySelectorAll('[data-reset-mailbox]').forEach((button) => button.addEventListener('click', () => resetMailboxPassword(button.dataset.resetMailbox)));
}

async function loadJournal() {
  const data = await getJSON('/api/audit');
  $('#journal-list').innerHTML = data.items.map((item) => `<div class="event-row"><span class="event-level ${item.level.toLowerCase()}">${item.level}</span><div><strong>${item.event}</strong><small>${item.details}</small></div><time>${formatDate(item.created_at)}</time></div>`).join('');
}

async function loadLogs() {
  const service = $('#log-service').value;
  const data = await getJSON(`/api/logs?service=${encodeURIComponent(service)}`);
  $('#system-logs').textContent = data.lines.length ? data.lines.join('\n') : 'Для этого сервиса журнал пуст или недоступен.';
}

async function loadSecurity() {
  const me = await getJSON('/api/auth/me');
  $('#security-status').textContent = me.totp_enabled ? '2FA включена' : '2FA не настроена';
  $('#setup-2fa').textContent = me.totp_enabled ? 'Перевыпустить секрет 2FA' : 'Настроить 2FA';
}

async function loadUsers() {
  const data = await getJSON('/api/users');
  $('#users-table').innerHTML = data.items.map((item) => `<tr><td><strong>${item.username}</strong></td><td><span class="status-pill">${item.role}</span></td><td>${item.totp_enabled ? 'включена' : 'нет'}</td><td>${item.last_login_at ? formatDate(item.last_login_at) : 'ещё не входил'}</td><td>${item.username === 'admin' ? '' : `<button class="danger-link" data-delete-user="${item.id}">Удалить</button>`}</td></tr>`).join('');
  document.querySelectorAll('[data-delete-user]').forEach((button) => button.addEventListener('click', () => deleteUser(button.dataset.deleteUser)));
}

async function deleteUser(id) {
  if (!confirm('Удалить пользователя?')) return;
  const response = await sendJSON(`/api/users/${id}`, {method: 'DELETE'});
  if (!response.ok) alert((await response.json()).error);
  await loadUsers();
}

async function loadMailboxDomains() {
  const data = await getJSON('/api/domains');
  $('#mailbox-domain').innerHTML = data.items.map((item) => `<option value="${item.id}">${item.name}</option>`).join('');
}

async function runDNS() {
  const domain = $('#dns-domain').value.trim();
  const selector = $('#dns-selector').value.trim();
  const data = await getJSON(`/api/diagnostics/dns?domain=${encodeURIComponent(domain)}&selector=${encodeURIComponent(selector)}`);
  $('#dns-results').innerHTML = data.checks.map((item) => `<div class="diag-row"><span class="${item.ok ? 'diag-ok' : 'diag-fail'}">${item.ok ? 'PASS' : 'FAIL'}</span><strong>${item.name}</strong><code>${item.value}</code></div>`).join('');
}

async function runSMTP() {
  const host = $('#smtp-host').value.trim();
  const port = $('#smtp-port').value;
  const data = await getJSON(`/api/diagnostics/smtp?host=${encodeURIComponent(host)}&port=${port}`);
  $('#smtp-results').innerHTML = `<div class="diag-row"><span class="${data.ok ? 'diag-ok' : 'diag-fail'}">${data.ok ? 'PASS' : 'FAIL'}</span><strong>${data.code || 'ERROR'}</strong><code>${data.banner || data.error}</code></div>`;
}

async function runSetup() {
  const response = await getJSON('/api/setup/plan');
  $('#setup-result').innerHTML = `<div class="setup-meta">Режим: <strong>${response.mode}</strong> · ОС: <strong>${response.release.PRETTY_NAME || response.release.ID}</strong></div>${response.steps.map((step) => `<div class="setup-row"><span class="${step.result === 'blocked' ? 'diag-fail' : 'diag-ok'}">${step.result}</span><strong>${step.name}</strong><code>${step.output}</code></div>`).join('')}`;
}

async function loadSettings() {
  const data = await getJSON('/api/settings');
  data.items.forEach((item) => { const field = $(`#setting-${item.key}`); if (field) field.value = item.value; });
}

async function saveSettings() {
  const payload = {};
  ['hostname', 'mail_domain', 'relay_mode', 'trusted_networks', 'smtp_listen', 'tls_mode'].forEach((key) => { payload[key] = $(`#setting-${key}`).value; });
  const response = await sendJSON('/api/settings', {method: 'PUT', body: JSON.stringify(payload)});
  const result = await response.json();
  const message = $('#settings-message'); message.textContent = response.ok ? 'Настройки сохранены.' : result.error; message.classList.remove('hidden'); message.classList.toggle('error', !response.ok);
}

function showOneTimeSecret(secret) { $('#one-time-secret').textContent = secret; $('#secret-modal').showModal(); }

async function resetMailboxPassword(id) {
  if (!confirm('Сгенерировать новый пароль? Старый пароль сразу перестанет работать.')) return;
  const response = await sendJSON(`/api/mailboxes/${id}/password`, {method: 'POST'});
  const result = await response.json();
  if (!response.ok) return alert(result.error);
  showOneTimeSecret(result.generated_password);
}

async function setup2FA() {
  const setupResponse = await sendJSON('/api/auth/totp/setup', {method: 'POST'});
  const setup = await setupResponse.json();
  if (!setupResponse.ok) return alert(setup.error);
  const output = $('#security-output');
  output.innerHTML = `<strong>Добавьте аккаунт в приложение-аутентификатор</strong><br>Секрет: <code>${setup.secret}</code><br><small>${setup.otpauth_uri}</small>`;
  output.classList.remove('hidden');
  const code = prompt('Введите текущий 6-значный код для включения 2FA:');
  if (!code) return;
  const enableResponse = await sendJSON('/api/auth/totp/enable', {method: 'POST', body: JSON.stringify({code})});
  const result = await enableResponse.json();
  if (!enableResponse.ok) return alert(result.error);
  alert('2FA включена. Сохраните резервный секрет в защищённом месте.');
  await loadSecurity();
}

async function changePassword() {
  const currentPassword = prompt('Текущий пароль:');
  if (!currentPassword) return;
  const newPassword = prompt('Новый пароль (минимум 14 символов):');
  if (!newPassword) return;
  const response = await sendJSON('/api/auth/password', {method: 'POST', body: JSON.stringify({current_password: currentPassword, new_password: newPassword})});
  const result = await response.json();
  alert(response.ok ? 'Пароль изменён.' : result.error);
}

async function deleteDomain(id) {
  if (!confirm('Удалить домен и все связанные ящики?')) return;
  await sendJSON(`/api/domains/${id}`, {method: 'DELETE'});
  await loadDomains();
}

async function deleteMailbox(id) {
  if (!confirm('Удалить почтовый ящик?')) return;
  await sendJSON(`/api/mailboxes/${id}`, {method: 'DELETE'});
  await loadMailboxes();
}

async function createDomain(data) {
  const response = await sendJSON('/api/domains', {method: 'POST', body: JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) { alert(result.error); return false; }
  await loadDomains();
  return result;
}

async function createMailbox(data) {
  const response = await sendJSON('/api/mailboxes', {method: 'POST', body: JSON.stringify(data)});
  const result = await response.json();
  if (!response.ok) { alert(result.error); return false; }
  await loadMailboxes();
  return result;
}

document.querySelectorAll('.nav-item').forEach((item) => item.addEventListener('click', () => showSection(item.dataset.section)));
$('#refresh').addEventListener('click', loadOverview);
$('#new-domain').addEventListener('click', () => $('#domain-modal').showModal());
$('#new-mailbox').addEventListener('click', async () => { await loadMailboxDomains(); $('#mailbox-modal').showModal(); });
$('#log-service').addEventListener('change', loadLogs);
$('#setup-2fa').addEventListener('click', setup2FA);
$('#change-password').addEventListener('click', changePassword);
$('#new-user').addEventListener('click', () => $('#user-modal').showModal());
$('#run-dns').addEventListener('click', runDNS);
$('#run-smtp').addEventListener('click', runSMTP);
$('#run-setup').addEventListener('click', runSetup);
$('#save-settings').addEventListener('click', saveSettings);
$('#domain-form').addEventListener('submit', async (event) => { event.preventDefault(); const data = Object.fromEntries(new FormData(event.target)); const response = await createDomain({...data, quota_mb: Number(data.quota_mb)}); if (response !== false) { event.target.closest('dialog').close(); } });
$('#mailbox-form').addEventListener('submit', async (event) => { event.preventDefault(); const data = Object.fromEntries(new FormData(event.target)); const response = await createMailbox({...data, domain_id: Number(data.domain_id), quota_mb: Number(data.quota_mb)}); if (response !== false) { event.target.closest('dialog').close(); showOneTimeSecret(response.generated_password); } });
$('#user-form').addEventListener('submit', async (event) => { event.preventDefault(); const data = Object.fromEntries(new FormData(event.target)); const response = await sendJSON('/api/users', {method: 'POST', body: JSON.stringify(data)}); const result = await response.json(); if (!response.ok) return alert(result.error); event.target.closest('dialog').close(); await loadUsers(); });
$('#logout').addEventListener('click', async () => { await sendJSON('/api/auth/logout', {method: 'POST'}); location.href = '/login'; });
(async () => {
  const response = await fetch('/api/auth/me');
  if (!response.ok) return;
  const me = await response.json();
  csrfToken = me.csrf_token;
  loadOverview();
})();
